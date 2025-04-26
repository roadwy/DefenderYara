
rule Trojan_Win32_Glupteba_GAA_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.GAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 11 81 c1 ?? ?? ?? ?? 29 c7 81 c6 ?? ?? ?? ?? 39 d9 ?? ?? c3 01 fe 29 fe } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}