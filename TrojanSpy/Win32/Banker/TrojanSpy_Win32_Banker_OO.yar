
rule TrojanSpy_Win32_Banker_OO{
	meta:
		description = "TrojanSpy:Win32/Banker.OO,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {73 65 6e 68 61 3d 00 00 ff ff ff ff 08 00 00 00 75 73 75 61 72 69 6f 3d 00 00 00 00 ff ff ff ff 05 00 00 00 62 61 73 65 3d 00 00 00 ff ff ff ff 05 00 00 00 73 67 64 62 3d 00 00 00 ff ff ff ff 08 00 00 00 6e 6f 6d 65 65 78 65 3d 00 00 00 00 ff ff ff ff 0d 00 00 00 5b 43 6f 6e 65 78 61 6f 45 72 72 6f 5d 00 00 00 ff ff ff ff 12 00 00 00 5b 53 65 6c 65 63 61 6f 42 61 6e 63 6f 45 72 72 6f 5d 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}