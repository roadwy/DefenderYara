
rule Trojan_Win32_Glupteba_GXZ_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.GXZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {29 c0 31 1a 40 42 39 fa 75 ?? 48 81 c0 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}