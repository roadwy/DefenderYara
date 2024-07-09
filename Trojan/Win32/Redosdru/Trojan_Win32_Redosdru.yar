
rule Trojan_Win32_Redosdru{
	meta:
		description = "Trojan:Win32/Redosdru,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_03_0 = {32 32 32 2e 31 38 36 2e [0-03] 2e [0-03] 3a [0-04] 2f 34 2e 6a 70 67 } //1
		$a_03_1 = {32 32 32 2e 31 38 36 2e 33 30 2e 31 38 36 3a [0-04] 2f 34 2e 64 6c 6c } //1
		$a_03_2 = {49 6e 74 65 72 6e 65 74 52 65 61 64 [0-10] 49 6e 74 65 72 6e 65 74 4f 70 65 6e 55 72 6c [0-10] 49 6e 74 65 72 6e 65 74 4f 70 65 6e } //5
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*5) >=6
 
}