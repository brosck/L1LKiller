<h1 align="center">「⚠️」 About L1LKiller</h1>

L1LKiller is a tool developed to exploit the `truesight.sys` driver of the Rogue Anti-Malware Driver 3.3 software through the BYOVD (Bring Your Own Vulnerable Driver) technique. About 1 year ago this vulnerability was fixed and currently the driver is present in [LOLDrivers](https://www.loldrivers.io/drivers/e0e93453-1007-4799-ad02-9b461b7e0398/) (Living Off The Land Drivers). I developed this project at the time of the release of the discovery of this driver, where I was able to successfully perform the test on Sophos EDR. Since there is already a mitigation, I decided to publish this project that I kept private for a while.

## Demonstration

https://github.com/user-attachments/assets/e9ec29cb-6869-44c2-8649-0a545c30d2e9

## Help

```
      __   _____    __ __ _ ____
     / /  <  / /   / //_/(_) / /__  _____
    / /   / / /   / ,<  / / / / _ \/ ___/
   / /___/ / /___/ /| |/ / / /  __/ /
  /_____/_/_____/_/ |_/_/_/_/\___/_/

            [Coded by MrEmpy]
                 [v1.0]

Usage: C:\Windows\Temp\L1LKiller\L1LKiller.exe [OPTIONS]
    Options:
      single,                   kill processes only once
      loop,                     kill processes in a loop

    Examples:
      L1LKiller.exe single
      L1LKiller.exe loop
```

## Usage
```
sc create l1lkiller binPath="C:\Windows\Temp\L1LKiller\L1LKiller.sys" type=kernel
sc start l1lkiller
.\L1LKiller.exe single
```
