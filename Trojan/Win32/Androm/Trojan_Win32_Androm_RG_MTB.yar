
rule Trojan_Win32_Androm_RG_MTB{
	meta:
		description = "Trojan:Win32/Androm.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {c1 ca 0d 3c 61 0f be c0 7c 03 83 e8 20 03 d0 41 8a 01 84 c0 75 ea } //1
		$a_03_1 = {33 d2 8b c6 f7 f3 8a 0c ?? 30 0c 3e 46 [0-06] 3b [0-06] 72 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}