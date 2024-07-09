
rule Trojan_Win32_Glupteba_MW_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.MW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 54 24 18 2b 4c 24 38 89 54 24 30 8b 54 24 30 8a 5c 24 0b 80 e3 [0-02] 07 88 5c 24 37 8b 74 24 10 8a 1c 16 88 5c 24 27 89 4c 24 20 8b 4c 24 20 c7 44 24 ?? ?? ?? ?? ?? 39 c8 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}