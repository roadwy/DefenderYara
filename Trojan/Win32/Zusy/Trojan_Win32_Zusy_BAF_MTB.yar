
rule Trojan_Win32_Zusy_BAF_MTB{
	meta:
		description = "Trojan:Win32/Zusy.BAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 52 0c 8a 14 1a 8a 1c 39 32 d3 83 c6 01 88 14 01 8b 45 ?? 0f 80 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}