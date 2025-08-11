
rule Trojan_Win32_Zusy_EAET_MTB{
	meta:
		description = "Trojan:Win32/Zusy.EAET!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b d0 8b d8 c1 ea 18 c1 eb 10 0f b6 d2 0f b6 92 ?? ?? ?? ?? 88 5c 24 11 8b d8 0f b6 c0 8a 80 ?? ?? ?? ?? 88 44 24 0f 33 c0 88 54 24 0c } //5
		$a_01_1 = {01 d1 01 d0 c7 01 4d 4a 43 3b 01 d1 01 d0 c7 01 44 36 4f a1 01 d1 01 d0 89 ec } //5
	condition:
		((#a_02_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}