
rule Trojan_Win32_Cobaltstrike_MB_MTB{
	meta:
		description = "Trojan:Win32/Cobaltstrike.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 86 80 00 00 00 8b 86 b4 00 00 00 8b d3 c1 ea 08 88 14 01 ff 86 9c 00 00 00 8b 8e 9c 00 00 00 8b 86 b4 00 00 00 88 1c 01 ff 86 9c 00 00 00 8b 86 ec 00 00 00 8b 96 88 00 00 00 2b c2 01 46 1c 81 fd e8 94 01 00 0f 8c } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}