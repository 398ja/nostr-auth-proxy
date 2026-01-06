package xyz.tcheeric.nostr.authproxy.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.TaskScheduler;
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler;

/**
 * Configuration for task scheduling (used for auth timeout).
 */
@Configuration
public class SchedulerConfig {

    /**
     * Creates a task scheduler for scheduling auth timeouts.
     *
     * @return the task scheduler
     */
    @Bean
    public TaskScheduler taskScheduler() {
        ThreadPoolTaskScheduler scheduler = new ThreadPoolTaskScheduler();
        scheduler.setPoolSize(2);
        scheduler.setThreadNamePrefix("auth-timeout-");
        scheduler.setDaemon(true);
        return scheduler;
    }
}
