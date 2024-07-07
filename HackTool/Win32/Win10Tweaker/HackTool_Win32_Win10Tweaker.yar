
rule HackTool_Win32_Win10Tweaker{
	meta:
		description = "HackTool:Win32/Win10Tweaker,SIGNATURE_TYPE_PEHSTR,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_01_0 = {6d 5f 49 73 52 65 70 30 4c 6f 6e 67 44 65 63 6f 64 65 72 73 } //1 m_IsRep0LongDecoders
		$a_01_1 = {6d 5f 49 73 52 65 70 47 30 44 65 63 6f 64 65 72 73 } //1 m_IsRepG0Decoders
		$a_01_2 = {6d 5f 50 6f 73 53 6c 6f 74 44 65 63 6f 64 65 72 } //1 m_PosSlotDecoder
		$a_01_3 = {53 54 41 54 68 72 65 61 64 41 74 74 72 69 62 75 74 65 } //1 STAThreadAttribute
		$a_01_4 = {57 69 6e 20 31 30 20 54 77 65 61 6b 65 72 } //5 Win 10 Tweaker
		$a_01_5 = {57 69 6e 5f 31 30 5f 54 77 65 61 6b 65 72 2e 46 6f 72 6d 31 2e 72 65 73 6f 75 72 63 65 73 } //5 Win_10_Tweaker.Form1.resources
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*5+(#a_01_5  & 1)*5) >=12
 
}