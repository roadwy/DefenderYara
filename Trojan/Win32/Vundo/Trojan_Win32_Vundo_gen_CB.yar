
rule Trojan_Win32_Vundo_gen_CB{
	meta:
		description = "Trojan:Win32/Vundo.gen!CB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {74 04 83 45 fc 06 8b 45 fc ff 14 85 ?? ?? [00 01 02] 10 } //1
		$a_03_1 = {10 ff d0 59 90 09 0a 00 89 ?? ?? [4f 4e 49] 79 ?? 68 ?? ?? (01|00) } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}