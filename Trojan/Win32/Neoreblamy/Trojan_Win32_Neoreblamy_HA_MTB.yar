
rule Trojan_Win32_Neoreblamy_HA_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.HA!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,10 00 10 00 03 00 00 "
		
	strings :
		$a_00_0 = {66 00 6f 00 72 00 66 00 69 00 6c 00 65 00 73 00 } //1 forfiles
		$a_00_1 = {77 00 73 00 63 00 72 00 69 00 70 00 74 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 63 00 6d 00 64 00 20 00 2f 00 43 00 20 00 40 00 46 00 4e 00 41 00 4d 00 45 00 } //5 wscript.exe /c cmd /C @FNAME
		$a_02_2 = {70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 64 00 61 00 74 00 61 00 [0-38] 2e 00 77 00 73 00 66 00 5e 00 } //10
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*5+(#a_02_2  & 1)*10) >=16
 
}