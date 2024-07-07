
rule Trojan_Win32_Caynamer_ACY_MTB{
	meta:
		description = "Trojan:Win32/Caynamer.ACY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {52 50 8b 81 20 01 00 00 0b 44 24 34 33 46 64 50 ff 15 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}