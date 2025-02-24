
rule Trojan_Win32_Dlass_GPPD_MTB{
	meta:
		description = "Trojan:Win32/Dlass.GPPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {5a f1 0c 00 4c f1 0c 00 3a f1 0c 00 28 f1 0c 00 14 f1 0c 00 00 f1 0c 00 f0 f0 0c 00 d6 f0 0c 00 c8 f0 0c 00 ba f0 0c 00 aa f0 0c 00 9a f0 0c } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}