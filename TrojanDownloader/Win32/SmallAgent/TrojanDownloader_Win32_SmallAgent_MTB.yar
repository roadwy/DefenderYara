
rule TrojanDownloader_Win32_SmallAgent_MTB{
	meta:
		description = "TrojanDownloader:Win32/SmallAgent!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 d2 33 c9 8a 8a ?? ?? ?? ?? 8b c1 83 e1 ?? d1 ?? 83 e0 ?? c1 e1 ?? 0b c1 35 ?? ?? ?? ?? 83 c0 ?? f7 d0 48 88 82 ?? ?? ?? ?? 42 81 fa ?? ?? ?? ?? 72 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule TrojanDownloader_Win32_SmallAgent_MTB_2{
	meta:
		description = "TrojanDownloader:Win32/SmallAgent!MTB,SIGNATURE_TYPE_PEHSTR,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_01_0 = {50 49 43 4f 5f 53 4f 43 4b 5f 45 56 5f 52 44 } //1 PICO_SOCK_EV_RD
		$a_01_1 = {50 49 43 4f 5f 53 4f 43 4b 5f 45 56 5f 57 52 } //1 PICO_SOCK_EV_WR
		$a_01_2 = {50 49 43 4f 5f 53 4f 43 4b 5f 45 56 5f 43 4f 4e 4e } //1 PICO_SOCK_EV_CONN
		$a_01_3 = {50 49 43 4f 5f 53 4f 43 4b 5f 45 56 5f 43 4c 4f 53 45 } //1 PICO_SOCK_EV_CLOSE
		$a_01_4 = {50 49 43 4f 5f 53 4f 43 4b 5f 45 56 5f 46 49 4e } //1 PICO_SOCK_EV_FIN
		$a_01_5 = {50 49 43 4f 5f 53 4f 43 4b 5f 45 56 5f 45 52 52 } //1 PICO_SOCK_EV_ERR
		$a_01_6 = {50 49 43 4f 5f 53 48 55 54 5f 52 44 } //1 PICO_SHUT_RD
		$a_01_7 = {50 49 43 4f 5f 53 48 55 54 5f 57 52 } //1 PICO_SHUT_WR
		$a_01_8 = {50 49 43 4f 5f 53 48 55 54 5f 52 44 57 52 } //1 PICO_SHUT_RDWR
		$a_01_9 = {64 65 6c 20 2f 66 20 2f 71 20 22 } //1 del /f /q "
		$a_01_10 = {72 61 6e 64 6f 6d 73 65 65 64 } //1 randomseed
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=11
 
}