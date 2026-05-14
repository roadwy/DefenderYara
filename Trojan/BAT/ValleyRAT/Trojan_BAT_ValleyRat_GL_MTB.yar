
rule Trojan_BAT_ValleyRat_GL_MTB{
	meta:
		description = "Trojan:BAT/ValleyRat.GL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {7b 37 41 37 41 32 42 39 37 2d 45 35 35 39 2d 34 41 35 31 2d 38 44 37 36 2d 45 45 45 34 30 35 46 30 43 37 39 33 7d } //2 {7A7A2B97-E559-4A51-8D76-EEE405F0C793}
		$a_01_1 = {4d 69 63 72 6f 73 6f 66 74 2e 43 6f 64 65 41 6e 61 6c 79 73 69 73 } //1 Microsoft.CodeAnalysis
		$a_01_2 = {57 72 69 74 65 50 61 63 6b 65 64 } //1 WritePacked
		$a_01_3 = {48 61 73 43 61 6c 6c 62 61 63 6b 73 } //1 HasCallbacks
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=5
 
}