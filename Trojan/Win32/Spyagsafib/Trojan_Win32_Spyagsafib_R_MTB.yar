
rule Trojan_Win32_Spyagsafib_R_MTB{
	meta:
		description = "Trojan:Win32/Spyagsafib.R!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {74 00 6f 00 70 00 69 00 63 00 3d 00 73 00 65 00 74 00 75 00 70 00 63 00 6d 00 64 00 6c 00 69 00 6e 00 65 00 } //1 topic=setupcmdline
		$a_01_1 = {2f 00 76 00 65 00 72 00 79 00 73 00 69 00 6c 00 65 00 6e 00 74 00 20 00 2f 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 3d 00 } //1 /verysilent /password=
		$a_01_2 = {50 61 73 73 77 6f 72 64 53 61 6c 74 } //1 PasswordSalt
		$a_01_3 = {7b 00 75 00 73 00 65 00 72 00 61 00 70 00 70 00 64 00 61 00 74 00 61 00 7d 00 5c 00 69 00 6d 00 61 00 67 00 65 00 66 00 69 00 6c 00 65 00 } //1 {userappdata}\imagefile
		$a_01_4 = {49 00 6e 00 6e 00 6f 00 53 00 65 00 74 00 75 00 70 00 4c 00 64 00 72 00 57 00 69 00 6e 00 64 00 6f 00 77 00 } //1 InnoSetupLdrWindow
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}