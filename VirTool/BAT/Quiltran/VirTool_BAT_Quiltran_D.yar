
rule VirTool_BAT_Quiltran_D{
	meta:
		description = "VirTool:BAT/Quiltran.D,SIGNATURE_TYPE_PEHSTR,0d 00 0d 00 0d 00 00 "
		
	strings :
		$a_01_0 = {3d 20 53 54 43 6c 69 65 6e 74 28 47 75 69 64 3a 20 47 75 69 64 28 61 72 67 76 5b 30 5d 29 } //1 = STClient(Guid: Guid(argv[0])
		$a_01_1 = {54 68 72 65 61 64 2e 53 6c 65 65 70 28 47 65 74 53 6c 65 65 70 41 6e 64 4a 69 74 74 65 72 28 29 29 } //1 Thread.Sleep(GetSleepAndJitter())
		$a_01_2 = {3d 20 63 68 61 6e 6e 65 6c 2e 4b 65 79 45 78 63 68 61 6e 67 65 28 65 6e 63 72 79 70 74 65 64 50 75 62 4b 65 79 29 } //1 = channel.KeyExchange(encryptedPubKey)
		$a_01_3 = {22 52 65 6c 65 61 73 65 49 64 22 } //1 "ReleaseId"
		$a_01_4 = {50 61 72 61 6d 65 74 65 72 73 2e 44 75 63 6b 79 } //1 Parameters.Ducky
		$a_01_5 = {50 61 72 61 6d 65 74 65 72 73 2e 50 69 70 65 6c 69 6e 65 } //1 Parameters.Pipeline
		$a_01_6 = {42 6f 6f 43 6f 6d 70 69 6c 65 72 28 } //1 BooCompiler(
		$a_01_7 = {62 79 74 65 73 5f 74 6f 5f 73 65 6e 64 2e 4c 65 6e 67 74 68 20 3d 3d 20 38 31 39 32 30 3a } //1 bytes_to_send.Length == 81920:
		$a_01_8 = {63 6d 64 20 3d 3d 20 27 43 6f 6d 70 69 6c 65 41 6e 64 52 75 6e 27 3a } //1 cmd == 'CompileAndRun':
		$a_01_9 = {63 6d 64 20 3d 3d 20 27 4a 69 74 74 65 72 27 3a } //1 cmd == 'Jitter':
		$a_01_10 = {63 6c 61 73 73 20 53 54 4a 6f 62 3a } //1 class STJob:
		$a_01_11 = {3d 20 48 65 78 32 42 69 6e 61 72 79 28 76 61 6c 75 65 29 } //1 = Hex2Binary(value)
		$a_01_12 = {47 75 69 64 2e 4e 65 77 47 75 69 64 28 29 2e 54 6f 53 74 72 69 6e 67 28 22 6e 22 29 2e 53 75 62 73 74 72 69 6e 67 28 30 2c 20 38 29 } //1 Guid.NewGuid().ToString("n").Substring(0, 8)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=13
 
}