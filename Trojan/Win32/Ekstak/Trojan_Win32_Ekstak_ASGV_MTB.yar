
rule Trojan_Win32_Ekstak_ASGV_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.ASGV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 83 ec 10 53 56 57 68 ?? ?? 4c 00 e8 ?? ?? f5 ff 83 c4 04 e9 } //4
		$a_01_1 = {41 00 6e 00 67 00 75 00 6c 00 61 00 72 00 20 00 4a 00 53 00 20 00 45 00 64 00 69 00 74 00 6f 00 72 00 } //1 Angular JS Editor
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}