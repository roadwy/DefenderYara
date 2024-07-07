
rule Trojan_Win32_NativeZone_D_dha{
	meta:
		description = "Trojan:Win32/NativeZone.D!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {4d 8b f7 49 8b dd 4d 2b f5 bf 02 00 00 00 0f 1f 84 00 00 00 00 00 4d 8d 04 1e 4c 8b ce 48 8b d3 48 8d 4c 24 38 e8 90 01 04 48 83 c3 10 48 83 ef 01 75 e2 48 8b ce e8 90 01 04 41 0f 10 07 48 8b 44 24 20 0f 11 45 00 41 0f 10 4f 10 0f 11 4d 10 48 83 c5 20 49 83 ec 01 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}