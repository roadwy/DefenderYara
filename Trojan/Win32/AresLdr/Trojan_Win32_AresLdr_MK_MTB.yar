
rule Trojan_Win32_AresLdr_MK_MTB{
	meta:
		description = "Trojan:Win32/AresLdr.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 ff 8b bd 90 01 04 8d 04 0e 8d 04 41 01 c8 2b 15 90 01 04 01 c2 01 f2 01 ca 01 ca 01 d6 8b 95 90 01 04 01 ce 01 f1 8b 35 90 01 04 8a 84 0e 90 01 04 8b 8d 90 01 04 32 04 1a 43 88 04 39 e9 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}