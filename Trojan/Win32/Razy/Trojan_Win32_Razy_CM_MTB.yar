
rule Trojan_Win32_Razy_CM_MTB{
	meta:
		description = "Trojan:Win32/Razy.CM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 f7 31 01 09 de 81 eb ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 81 ef ?? ?? ?? ?? 29 db 39 d1 75 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}