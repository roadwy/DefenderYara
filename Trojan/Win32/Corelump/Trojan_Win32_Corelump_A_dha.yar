
rule Trojan_Win32_Corelump_A_dha{
	meta:
		description = "Trojan:Win32/Corelump.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_43_0 = {c9 ff 15 90 01 04 90 02 03 81 78 02 45 9e be bd 90 00 01 } //1
		$a_5d_1 = {3e } //4096 >
	condition:
		((#a_43_0  & 1)*1+(#a_5d_1  & 1)*4096) >=1
 
}