
rule Trojan_Win32_Farfli_V_MTB{
	meta:
		description = "Trojan:Win32/Farfli.V!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f bc fd 01 ff 29 d1 f7 d8 8d 45 90 01 01 66 0f ac e7 90 01 01 d3 cf 24 fc 66 0f be f8 66 0f ad cf 66 81 df 90 01 02 29 c8 66 f7 d7 66 0f be f8 66 0f cf 66 0f be fa 89 c4 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}