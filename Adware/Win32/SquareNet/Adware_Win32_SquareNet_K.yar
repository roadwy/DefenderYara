
rule Adware_Win32_SquareNet_K{
	meta:
		description = "Adware:Win32/SquareNet.K,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 00 52 00 65 00 67 00 69 00 73 00 74 00 72 00 79 00 5c 00 4d 00 61 00 63 00 68 00 69 00 6e 00 65 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 5c 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 5c 00 75 00 64 00 69 00 73 00 6b 00 4d 00 67 00 72 00 } //1 \Registry\Machine\System\CurrentControlSet\services\udiskMgr
		$a_01_1 = {5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 44 00 72 00 76 00 50 00 72 00 6f 00 74 00 65 00 63 00 74 00 } //1 \DosDevices\DrvProtect
		$a_01_2 = {5c 00 52 00 65 00 67 00 69 00 73 00 74 00 72 00 79 00 5c 00 4d 00 61 00 63 00 68 00 69 00 6e 00 65 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 5c 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 5c 00 6d 00 73 00 69 00 64 00 6e 00 74 00 66 00 73 00 } //1 \Registry\Machine\System\CurrentControlSet\services\msidntfs
		$a_01_3 = {5c 53 50 59 48 55 4e 54 45 52 34 2e 45 58 45 } //1 \SPYHUNTER4.EXE
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}