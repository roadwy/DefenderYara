
rule Trojan_Win64_Cobaltstrike_GOP_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.GOP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 c9 48 8d 52 01 49 83 f9 1c 49 0f 45 c9 41 ff c0 42 0f b6 04 11 4c 8d 49 01 30 42 ff 49 63 c0 48 3b c3 72 db } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}