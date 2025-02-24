
rule Trojan_Win64_Tedy_GPK_MTB{
	meta:
		description = "Trojan:Win64/Tedy.GPK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_81_0 = {49 6d 67 75 69 2d 42 6c 75 65 2d 6c 6f 61 64 65 72 2d 6d 61 73 74 65 72 5c 49 6d 67 75 69 2d 42 6c 75 65 2d 6c 6f 61 64 65 72 2d 6d 61 73 74 65 72 5c 49 6d 47 75 69 5c 69 6d 73 74 62 5f 74 65 78 74 65 64 69 74 2e 68 } //3 Imgui-Blue-loader-master\Imgui-Blue-loader-master\ImGui\imstb_textedit.h
		$a_81_1 = {62 6c 75 65 5f 6c 6f 61 64 65 72 5f 69 6d 67 75 69 } //2 blue_loader_imgui
	condition:
		((#a_81_0  & 1)*3+(#a_81_1  & 1)*2) >=5
 
}