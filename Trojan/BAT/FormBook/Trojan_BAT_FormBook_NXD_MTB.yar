
rule Trojan_BAT_FormBook_NXD_MTB{
	meta:
		description = "Trojan:BAT/FormBook.NXD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {24 37 65 61 34 33 30 35 39 2d 66 65 61 61 2d 34 62 62 64 2d 38 64 31 32 2d 30 61 37 36 39 35 32 35 64 32 31 65 } //1 $7ea43059-feaa-4bbd-8d12-0a769525d21e
		$a_01_1 = {53 68 6f 74 67 75 6e 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 Shotgun.Properties.Resources.resources
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_01_3 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
		$a_01_4 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}