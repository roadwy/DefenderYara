
rule Trojan_Win32_Daonol_M{
	meta:
		description = "Trojan:Win32/Daonol.M,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {58 8d 4d d0 [0-0a] 66 4b [0-0a] ff 34 37 [0-0a] 33 41 fc [0-0a] 46 [0-0a] c1 e0 08 [0-0a] 88 64 37 ff [0-0a] 4f [0-0a] 75 } //1
		$a_03_1 = {8d 4d d0 66 4b [0-0a] ff 34 37 [0-0a] 8b 49 fc [0-0a] 31 c8 [0-0a] 90 17 03 0c 06 06 46 [0-0a] c1 90 04 01 02 e0 c0 08 d3 c8 [0-0a] 46 46 [0-0a] d3 c8 [0-0a] 88 90 04 01 02 64 44 37 ff [0-0a] 4f [0-0a] 75 90 14 [0-0a] 46 [0-0a] (81|83) c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}