
rule Trojan_Win32_Nymaim_BAF_MTB{
	meta:
		description = "Trojan:Win32/Nymaim.BAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {50 59 51 29 c0 0b 02 f8 83 d2 04 83 e8 2c } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}