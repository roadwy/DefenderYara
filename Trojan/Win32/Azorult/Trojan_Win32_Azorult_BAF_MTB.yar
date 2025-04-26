
rule Trojan_Win32_Azorult_BAF_MTB{
	meta:
		description = "Trojan:Win32/Azorult.BAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 07 83 ef fc f7 d8 8d 40 d7 83 c0 fe 40 29 d0 29 d2 09 c2 6a 00 8f 03 01 03 83 eb fc 83 ee fc } //3
	condition:
		((#a_01_0  & 1)*3) >=3
 
}