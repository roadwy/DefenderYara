
rule Trojan_Win32_Proxage_A_dha{
	meta:
		description = "Trojan:Win32/Proxage.A!dha,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4d 69 72 61 67 65 46 6f 78 } //1 MirageFox
		$a_01_1 = {2e 6d 65 63 68 61 6e 69 63 6e 6f 74 65 2e 63 6f 6d } //1 .mechanicnote.com
		$a_01_2 = {2f 73 65 61 72 63 68 3f 67 69 64 3d 25 73 } //1 /search?gid=%s
		$a_01_3 = {2f 63 20 64 65 6c 20 25 73 20 3e 20 6e 75 6c } //1 /c del %s > nul
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}