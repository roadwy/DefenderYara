
rule Trojan_Win32_BlackShades_MBWB_MTB{
	meta:
		description = "Trojan:Win32/BlackShades.MBWB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c0 23 40 00 b0 12 40 00 00 f0 30 00 00 ff ff ff 08 00 00 00 01 00 00 00 00 00 00 00 e9 00 00 00 28 11 40 00 28 11 40 00 ec 10 40 00 78 00 00 00 80 00 00 00 83 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}