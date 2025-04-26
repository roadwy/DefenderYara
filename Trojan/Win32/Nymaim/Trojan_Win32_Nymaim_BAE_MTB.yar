
rule Trojan_Win32_Nymaim_BAE_MTB{
	meta:
		description = "Trojan:Win32/Nymaim.BAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 c0 33 01 83 e9 fc f8 83 d0 d4 c1 c8 08 29 d8 83 c0 ff 89 c3 c1 c3 08 50 8f 02 8d 52 04 f8 83 d6 fc 85 f6 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}