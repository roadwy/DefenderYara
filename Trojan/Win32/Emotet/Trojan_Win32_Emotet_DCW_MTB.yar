
rule Trojan_Win32_Emotet_DCW_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DCW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_02_0 = {03 c3 99 f7 f9 [0-17] 03 c1 99 b9 [0-04] f7 f9 } //1
		$a_00_1 = {8b 4c 24 14 8b 54 24 18 8b c1 8b f2 f7 d0 f7 d6 5f 0b c6 5e 0b ca 5d 23 c1 } //1
		$a_02_2 = {03 c2 99 f7 fb 0f b6 04 32 8b 54 24 ?? 0f be 54 0a ?? 8a d8 f6 d2 f6 d3 0a da 8b 54 24 ?? 0f be 54 0a ?? 0a c2 22 d8 83 6c 24 [0-02] 88 59 } //2
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*2) >=2
 
}