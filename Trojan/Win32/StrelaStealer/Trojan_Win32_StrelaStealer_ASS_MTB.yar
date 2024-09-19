
rule Trojan_Win32_StrelaStealer_ASS_MTB{
	meta:
		description = "Trojan:Win32/StrelaStealer.ASS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c1 c0 05 8a cb d3 ca 8b 4c 24 10 2b 31 83 6c 24 10 08 33 d0 8a c8 8b 44 24 14 d3 ce 48 89 44 24 14 33 f3 85 c0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}