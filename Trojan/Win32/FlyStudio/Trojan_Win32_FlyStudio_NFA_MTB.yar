
rule Trojan_Win32_FlyStudio_NFA_MTB{
	meta:
		description = "Trojan:Win32/FlyStudio.NFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {eb 02 33 f6 8b 45 08 83 4d fc ?? 89 46 08 8d 45 08 68 38 c9 5a 00 } //5
		$a_01_1 = {7a 68 65 6e 67 } //1 zheng
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}