
rule PWS_Win32_AgentTesla_YA_MTB{
	meta:
		description = "PWS:Win32/AgentTesla.YA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 20 00 63 00 6f 00 75 00 6c 00 64 00 20 00 6e 00 6f 00 74 00 20 00 64 00 65 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 2e 00 } //1 Password could not decrypted.
		$a_01_1 = {68 00 6f 00 73 00 74 00 6e 00 61 00 6d 00 65 00 7c 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 7c 00 65 00 6e 00 63 00 72 00 79 00 70 00 74 00 65 00 64 00 55 00 73 00 65 00 72 00 6e 00 61 00 6d 00 65 00 } //1 hostname|encryptedPassword|encryptedUsername
		$a_01_2 = {50 00 61 00 74 00 68 00 3d 00 28 00 5b 00 41 00 2d 00 7a 00 30 00 2d 00 39 00 5c 00 2f 00 5c 00 2e 00 5d 00 2b 00 29 00 } //1 Path=([A-z0-9\/\.]+)
		$a_01_3 = {5c 00 54 00 68 00 75 00 6e 00 64 00 65 00 72 00 62 00 69 00 72 00 64 00 5c 00 } //1 \Thunderbird\
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}