
rule HackTool_MacOS_SuspBinary_X{
	meta:
		description = "HackTool:MacOS/SuspBinary.X,SIGNATURE_TYPE_MACHOHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_00_0 = {43 79 6d 75 6c 61 74 65 52 65 76 65 72 73 65 53 68 65 6c 6c } //1 CymulateReverseShell
		$a_00_1 = {43 79 6d 75 6c 61 74 65 43 6f 69 6e 4d 69 6e 65 72 43 6f 72 65 } //1 CymulateCoinMinerCore
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=1
 
}