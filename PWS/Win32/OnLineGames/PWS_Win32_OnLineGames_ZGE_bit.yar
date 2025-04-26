
rule PWS_Win32_OnLineGames_ZGE_bit{
	meta:
		description = "PWS:Win32/OnLineGames.ZGE!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4f 6e 43 6c 69 70 62 6f 61 72 64 43 68 61 6e 67 65 } //1 OnClipboardChange
		$a_01_1 = {46 69 6c 65 53 65 74 41 74 74 72 69 62 2c 20 2b 48 2b 53 } //1 FileSetAttrib, +H+S
		$a_01_2 = {73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 74 6e 20 53 79 73 74 65 6d 5c 53 79 73 74 65 6d 44 6f 6e 65 } //1 schtasks /create /tn System\SystemDone
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}