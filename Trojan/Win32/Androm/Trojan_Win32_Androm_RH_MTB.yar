
rule Trojan_Win32_Androm_RH_MTB{
	meta:
		description = "Trojan:Win32/Androm.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 c9 0d 8b c1 c3 [0-20] 0f be ca 80 fa 61 7c 03 83 e9 20 03 c1 46 8a 16 84 d2 75 e3 [0-a0] 33 d2 8b c6 f7 75 ?? 8a 0c 1a 30 0c 3e 46 3b 75 ?? 72 ed } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}