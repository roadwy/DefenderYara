
rule HackTool_MacOS_Keygen_MTB{
	meta:
		description = "HackTool:MacOS/Keygen!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_02_0 = {43 4f 52 45 20 4b 65 79 67 65 6e 2e 62 75 69 6c 64 2f 4f 62 6a 65 63 74 73 2d 6e 6f 72 6d 61 6c 2f 90 02 04 2f 6d 61 69 6e 2e 6f 90 00 } //1
		$a_02_1 = {43 4f 52 45 5f 4b 47 2e 62 75 69 6c 64 2f 4f 62 6a 65 63 74 73 2d 6e 6f 72 6d 61 6c 2f 90 02 04 2f 6d 61 69 6e 2e 6f 90 00 } //1
		$a_00_2 = {4b 47 53 65 72 69 61 6c 4e 75 6d 62 65 72 47 65 6e 65 72 61 74 6f 72 20 63 72 65 61 74 65 53 65 72 69 61 6c 3a } //1 KGSerialNumberGenerator createSerial:
		$a_00_3 = {5f 6d 6f 75 73 65 49 73 48 6f 76 65 72 69 6e 67 } //1 _mouseIsHovering
		$a_00_4 = {43 4f 52 45 20 4b 65 79 67 65 6e } //1 CORE Keygen
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}