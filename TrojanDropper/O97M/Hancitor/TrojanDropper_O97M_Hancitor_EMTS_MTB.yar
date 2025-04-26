
rule TrojanDropper_O97M_Hancitor_EMTS_MTB{
	meta:
		description = "TrojanDropper:O97M/Hancitor.EMTS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {65 64 67 65 2e 64 } //1 edge.d
		$a_01_1 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 28 22 6e 6d 22 2c 20 6f 6c 6f 6c 6f 77 29 } //1 Application.Run("nm", ololow)
		$a_01_2 = {53 75 62 20 6a 6f 70 28 75 75 75 20 41 73 20 53 74 72 69 6e 67 2c 20 61 61 61 61 20 41 73 20 53 74 72 69 6e 67 29 } //1 Sub jop(uuu As String, aaaa As String)
		$a_01_3 = {43 61 6c 6c 20 72 6e 65 65 28 75 75 75 2c 20 61 61 61 61 29 } //1 Call rnee(uuu, aaaa)
		$a_01_4 = {43 61 6c 6c 20 73 74 65 74 70 74 77 77 6f } //1 Call stetptwwo
		$a_01_5 = {3d 20 56 42 41 2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //1 = VBA.CreateObject("WScript.Shell")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}