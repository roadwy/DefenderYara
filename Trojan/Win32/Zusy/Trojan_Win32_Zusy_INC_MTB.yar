
rule Trojan_Win32_Zusy_INC_MTB{
	meta:
		description = "Trojan:Win32/Zusy.INC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {53 55 bb 95 1f 24 2d 9c bd 16 51 af 27 f7 d3 } //3
	condition:
		((#a_01_0  & 1)*3) >=3
 
}