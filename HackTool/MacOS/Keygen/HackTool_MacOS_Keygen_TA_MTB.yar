
rule HackTool_MacOS_Keygen_TA_MTB{
	meta:
		description = "HackTool:MacOS/Keygen.TA!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_00_0 = {43 4f 52 45 20 4b 65 79 67 65 6e } //1 CORE Keygen
		$a_00_1 = {53 65 72 69 61 6c 46 69 65 6c 64 42 47 } //1 SerialFieldBG
		$a_00_2 = {4b 47 53 65 72 69 61 6c 4e 75 6d 62 65 72 47 65 6e 65 72 61 74 6f 72 } //1 KGSerialNumberGenerator
		$a_00_3 = {6d 6f 75 73 65 49 73 48 6f 76 65 72 69 6e 67 } //1 mouseIsHovering
		$a_00_4 = {50 61 74 63 68 65 72 } //1 Patcher
		$a_00_5 = {63 72 65 61 74 65 53 65 72 69 61 6c } //1 createSerial
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=4
 
}