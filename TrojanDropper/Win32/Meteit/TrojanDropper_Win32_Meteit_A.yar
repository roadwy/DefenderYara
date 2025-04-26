
rule TrojanDropper_Win32_Meteit_A{
	meta:
		description = "TrojanDropper:Win32/Meteit.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 53 49 47 4e 55 50 5c 2a 2e 69 6e 73 } //1 Internet Explorer\SIGNUP\*.ins
		$a_03_1 = {5c 6d 73 61 64 6f [0-04] 2e } //1
		$a_03_2 = {83 c4 14 8d 85 ?? ?? ff ff 68 ?? ?? ?? ?? 50 8d 45 ?? 50 ff 15 ?? ?? ?? ?? 8d 85 ?? ?? ff ff 50 8d 85 ?? ?? ff ff 50 ff 15 ?? ?? ?? ?? 83 f8 ff 74 09 8d 85 ?? ?? ff ff 50 ff d7 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}