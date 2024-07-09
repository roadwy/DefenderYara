
rule Trojan_Win32_Kimsuku_A_MSR{
	meta:
		description = "Trojan:Win32/Kimsuku.A!MSR,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 0c 3a 8d 52 01 80 e9 ?? 88 4a ff 83 e8 01 75 ef } //1
		$a_00_1 = {6b 6f 6d 61 64 } //1 komad
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}