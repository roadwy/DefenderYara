
rule Ransom_Win32_Hive_SA{
	meta:
		description = "Ransom:Win32/Hive.SA,SIGNATURE_TYPE_CMDHSTR_EXT,65 00 65 00 03 00 00 "
		
	strings :
		$a_00_0 = {63 00 6d 00 64 00 } //1 cmd
		$a_00_1 = {5c 00 6e 00 65 00 74 00 6c 00 6f 00 67 00 6f 00 6e 00 5c 00 78 00 78 00 78 00 2e 00 65 00 78 00 65 00 20 00 2d 00 75 00 } //100 \netlogon\xxx.exe -u
		$a_00_2 = {5c 00 6e 00 65 00 74 00 6c 00 6f 00 67 00 6f 00 6e 00 5c 00 78 00 78 00 78 00 78 00 2e 00 65 00 78 00 65 00 20 00 2d 00 75 00 } //100 \netlogon\xxxx.exe -u
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*100+(#a_00_2  & 1)*100) >=101
 
}