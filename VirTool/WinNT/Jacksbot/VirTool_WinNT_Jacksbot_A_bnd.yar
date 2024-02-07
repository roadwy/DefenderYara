
rule VirTool_WinNT_Jacksbot_A_bnd{
	meta:
		description = "VirTool:WinNT/Jacksbot.A!bnd,SIGNATURE_TYPE_JAVAHSTR_EXT,2d 00 2d 00 10 00 00 05 00 "
		
	strings :
		$a_01_0 = {6a 61 76 61 2f 69 6f 2f 46 69 6c 65 4f 75 74 70 75 74 53 74 72 65 61 6d } //05 00  java/io/FileOutputStream
		$a_01_1 = {6a 61 76 61 2f 69 6f 2f 49 6e 70 75 74 53 74 72 65 61 6d } //05 00  java/io/InputStream
		$a_01_2 = {6a 61 76 61 2f 6c 61 6e 67 2f 53 74 72 69 6e 67 } //05 00  java/lang/String
		$a_01_3 = {6a 61 76 61 2f 6c 61 6e 67 2f 53 79 73 74 65 6d } //02 00  java/lang/System
		$a_00_4 = {67 65 74 52 65 73 6f 75 72 63 65 41 73 53 74 72 65 61 6d } //02 00  getResourceAsStream
		$a_01_5 = {67 65 74 52 75 6e 74 69 6d 65 } //02 00  getRuntime
		$a_01_6 = {67 65 74 41 62 73 6f 6c 75 74 65 50 61 74 68 } //02 00  getAbsolutePath
		$a_01_7 = {63 72 65 61 74 65 54 65 6d 70 46 69 6c 65 } //02 00  createTempFile
		$a_01_8 = {6a 61 76 61 78 2f 63 72 79 70 74 6f 2f 73 70 65 63 2f 53 65 63 72 65 74 4b 65 79 53 70 65 63 } //02 00  javax/crypto/spec/SecretKeySpec
		$a_01_9 = {6a 61 76 61 2f 73 65 63 75 72 69 74 79 2f 73 70 65 63 2f 41 6c 67 6f 72 69 74 68 6d 50 61 72 61 6d 65 74 65 72 53 70 65 63 } //02 00  java/security/spec/AlgorithmParameterSpec
		$a_01_10 = {6a 61 76 61 2f 6e 65 74 2f 55 52 4c } //02 00  java/net/URL
		$a_01_11 = {6a 61 76 61 2f 73 65 63 75 72 69 74 79 2f 43 6f 64 65 53 6f 75 72 63 65 } //02 00  java/security/CodeSource
		$a_01_12 = {6a 61 76 61 2f 73 65 63 75 72 69 74 79 2f 50 72 6f 74 65 63 74 69 6f 6e 44 6f 6d 61 69 6e } //02 00  java/security/ProtectionDomain
		$a_01_13 = {6a 61 76 61 2f 69 6f 2f 42 75 66 66 65 72 65 64 57 72 69 74 65 72 } //05 00  java/io/BufferedWriter
		$a_01_14 = {10 32 b6 19 bb 59 b2 10 32 b7 19 b6 b6 } //05 00 
		$a_01_15 = {12 b7 19 b6 b6 12 b6 12 b6 19 b6 12 b6 b6 b6 } //00 00 
		$a_00_16 = {5d 04 00 00 02 ce 02 80 5c 24 00 00 04 ce 02 80 00 00 01 00 1e 00 0e 00 d1 41 42 6c 61 63 6f 6c 65 52 65 66 2e 41 00 00 } //01 40 
	condition:
		any of ($a_*)
 
}