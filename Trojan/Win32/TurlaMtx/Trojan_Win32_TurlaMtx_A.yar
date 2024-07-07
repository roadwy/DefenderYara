
rule Trojan_Win32_TurlaMtx_A{
	meta:
		description = "Trojan:Win32/TurlaMtx.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 0f 00 00 "
		
	strings :
		$a_80_0 = {63 61 72 62 6f 6e } //carbon  4
		$a_80_1 = {47 6c 6f 62 61 6c 5c 4d 53 43 54 46 2e 53 68 61 72 65 64 2e 4d 55 54 45 58 2e 5a 52 58 } //Global\MSCTF.Shared.MUTEX.ZRX  1
		$a_80_2 = {47 6c 6f 62 61 6c 5c 44 42 57 69 6e 64 6f 77 73 42 61 73 65 } //Global\DBWindowsBase  1
		$a_80_3 = {47 6c 6f 62 61 6c 5c 49 45 46 72 61 6d 65 2e 4c 6f 63 6b 44 65 66 61 75 6c 74 42 72 6f 77 73 65 72 } //Global\IEFrame.LockDefaultBrowser  1
		$a_80_4 = {47 6c 6f 62 61 6c 5c 57 69 6e 53 74 61 30 5f 44 65 73 6b 74 6f 70 53 65 73 73 69 6f 6e 4d 75 74 } //Global\WinSta0_DesktopSessionMut  1
		$a_80_5 = {47 6c 6f 62 61 6c 5c 7b 35 46 41 33 42 43 30 32 2d 39 32 30 46 2d 44 34 32 41 2d 36 38 42 43 2d 30 34 46 32 41 37 35 42 45 31 35 38 7d } //Global\{5FA3BC02-920F-D42A-68BC-04F2A75BE158}  1
		$a_80_6 = {47 6c 6f 62 61 6c 5c 53 45 4e 53 2e 4c 6f 63 6b 53 74 61 72 74 65 72 43 61 63 68 65 52 65 73 6f 75 72 63 65 } //Global\SENS.LockStarterCacheResource  1
		$a_80_7 = {47 6c 6f 62 61 6c 5c 53 68 69 6d 53 68 61 72 65 64 4d 65 6d 6f 72 79 4c 6f 63 6b } //Global\ShimSharedMemoryLock  1
		$a_80_8 = {47 6c 6f 62 61 6c 5c 53 74 61 63 6b 2e 54 72 61 63 65 2e 4d 75 6c 74 69 2e 54 4f 53 } //Global\Stack.Trace.Multi.TOS  1
		$a_80_9 = {47 6c 6f 62 61 6c 5c 44 61 74 61 62 61 73 65 54 72 61 6e 73 53 65 63 75 72 69 74 79 4c 6f 63 6b } //Global\DatabaseTransSecurityLock  1
		$a_80_10 = {47 6c 6f 62 61 6c 5c 45 78 63 68 61 6e 67 65 2e 50 72 6f 70 65 72 74 69 65 73 2e 42 } //Global\Exchange.Properties.B  1
		$a_80_11 = {47 6c 6f 62 61 6c 5c 54 72 61 63 6b 46 69 72 6c 65 53 79 73 74 65 6d 49 6e 74 65 67 72 69 74 79 } //Global\TrackFirleSystemIntegrity  1
		$a_80_12 = {47 6c 6f 62 61 6c 5c 42 69 74 73 77 61 70 4e 6f 72 6d 61 6c 4f 70 73 } //Global\BitswapNormalOps  1
		$a_80_13 = {47 6c 6f 62 61 6c 5c 56 42 5f 63 72 79 70 74 6f 5f 6c 69 62 72 61 72 79 5f 62 61 63 6b 65 6e 64 } //Global\VB_crypto_library_backend  1
		$a_80_14 = {47 6c 6f 62 61 6c 5c 7b 45 34 31 42 39 41 46 34 2d 42 34 45 31 2d 30 36 33 42 2d 37 33 35 32 2d 34 41 42 36 45 38 46 33 35 35 43 37 7d } //Global\{E41B9AF4-B4E1-063B-7352-4AB6E8F355C7}  1
	condition:
		((#a_80_0  & 1)*4+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1+(#a_80_12  & 1)*1+(#a_80_13  & 1)*1+(#a_80_14  & 1)*1) >=5
 
}