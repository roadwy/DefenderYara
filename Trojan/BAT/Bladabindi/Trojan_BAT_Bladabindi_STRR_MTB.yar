
rule Trojan_BAT_Bladabindi_STRR_MTB{
	meta:
		description = "Trojan:BAT/Bladabindi.STRR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {54 56 71 51 41 41 4d 41 41 41 41 45 41 41 41 41 2f 2f } //1 TVqQAAMAAAAEAAAA//
		$a_81_1 = {49 47 4e 68 62 6d 35 76 64 43 42 69 5a 53 42 79 64 57 34 67 61 57 34 67 } //1 IGNhbm5vdCBiZSBydW4gaW4g
		$a_81_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //1 FromBase64String
		$a_81_3 = {46 72 61 6d 65 77 6f 72 6b 44 69 73 70 6c 61 79 4e 61 6d 65 } //1 FrameworkDisplayName
		$a_81_4 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_81_5 = {67 65 74 5f 41 73 73 65 6d 62 6c 79 } //1 get_Assembly
		$a_00_6 = {24 66 36 36 35 39 31 38 62 2d 62 32 61 34 2d 34 62 62 33 2d 39 36 38 64 2d 37 35 37 30 62 34 36 66 62 34 37 38 } //1 $f665918b-b2a4-4bb3-968d-7570b46fb478
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}
rule Trojan_BAT_Bladabindi_STRR_MTB_2{
	meta:
		description = "Trojan:BAT/Bladabindi.STRR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_81_0 = {4b 65 79 50 72 65 73 73 45 76 65 6e 74 41 72 67 73 } //1 KeyPressEventArgs
		$a_81_1 = {42 69 6e 61 72 79 4d 61 73 6b } //1 BinaryMask
		$a_81_2 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //1 DebuggerHiddenAttribute
		$a_81_3 = {48 69 64 65 4d 6f 64 75 6c 65 4e 61 6d 65 41 74 74 72 69 62 75 74 65 } //1 HideModuleNameAttribute
		$a_81_4 = {4d 65 6d 6f 72 79 53 74 72 65 61 6d } //1 MemoryStream
		$a_81_5 = {4c 6f 61 64 46 69 6c 65 } //1 LoadFile
		$a_81_6 = {53 6d 74 70 43 6c 69 65 6e 74 } //1 SmtpClient
		$a_81_7 = {52 65 73 75 6d 65 4c 61 79 6f 75 74 } //1 ResumeLayout
		$a_81_8 = {63 75 62 65 6c 2e 75 73 65 72 73 70 70 72 74 61 64 64 72 73 73 40 67 6d 61 69 6c 2e 63 6f 6d } //1 cubel.userspprtaddrss@gmail.com
		$a_00_9 = {24 38 62 61 32 39 62 38 64 2d 61 36 32 37 2d 34 35 63 30 2d 61 61 66 66 2d 61 37 30 37 36 37 39 33 35 33 38 66 } //1 $8ba29b8d-a627-45c0-aaff-a7076793538f
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_00_9  & 1)*1) >=10
 
}