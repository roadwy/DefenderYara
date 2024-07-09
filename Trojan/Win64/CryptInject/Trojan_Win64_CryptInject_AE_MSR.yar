
rule Trojan_Win64_CryptInject_AE_MSR{
	meta:
		description = "Trojan:Win64/CryptInject.AE!MSR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 55 00 6e 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 5c 00 70 00 64 00 66 00 72 00 65 00 61 00 64 00 65 00 72 00 } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\pdfreader
		$a_00_1 = {2f 00 53 00 20 00 2f 00 75 00 69 00 64 00 3d 00 75 00 70 00 64 00 61 00 74 00 65 00 } //1 /S /uid=update
		$a_02_2 = {66 61 63 65 62 6f 6f 6b [0-08] 5f 6e 65 77 76 65 72 73 69 6f 6e 5c 64 61 74 61 62 61 73 65 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 57 69 6e 68 74 74 70 5f 36 34 2e 70 64 62 } //1
		$a_00_3 = {5b 41 6d 61 7a 6f 6e 5d 20 53 65 6e 64 52 75 6e 6e 69 6e 67 20 63 61 6e 20 6e 6f 74 20 66 69 6e 64 20 72 65 67 69 73 74 65 72 } //1 [Amazon] SendRunning can not find register
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}