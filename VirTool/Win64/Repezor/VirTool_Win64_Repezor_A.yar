
rule VirTool_Win64_Repezor_A{
	meta:
		description = "VirTool:Win64/Repezor.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {78 39 30 35 7d 4f 0f 94 c0 } //01 00 
		$a_00_1 = {7a 4b 21 44 6a 79 69 4d 44 4b 2e 25 58 71 25 46 33 67 4f 39 66 73 6e 72 29 42 2e 50 72 46 7a 4a 5f 2a 79 78 2c 7a 39 } //01 00  zK!DjyiMDK.%Xq%F3gO9fsnr)B.PrFzJ_*yx,z9
		$a_00_2 = {41 70 32 58 75 6d 27 57 75 57 65 25 48 64 65 2f 67 4f 36 67 21 50 2e 27 41 2b 63 4c 56 49 51 6e 55 50 63 65 62 68 64 } //01 00  Ap2Xum'WuWe%Hde/gO6g!P.'A+cLVIQnUPcebhd
		$a_00_3 = {30 3a 2f 70 6c 75 67 69 6e 73 2f 72 6f 6f 74 6b 69 74 2f 62 69 6e 61 72 79 } //00 00  0:/plugins/rootkit/binary
		$a_00_4 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}