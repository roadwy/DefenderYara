
rule Trojan_Win32_RemcosRAT_NRR_MTB{
	meta:
		description = "Trojan:Win32/RemcosRAT.NRR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {d3 a5 57 5a 03 90 bc 9f bf c9 e1 96 22 48 12 c7 80 b3 f8 fb 9d 8a c7 81 f3 78 89 69 ed 88 60 ca 30 6b bd 00 ce b4 aa ea 91 1b ff } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}