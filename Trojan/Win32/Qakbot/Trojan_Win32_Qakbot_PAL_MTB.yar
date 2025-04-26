
rule Trojan_Win32_Qakbot_PAL_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.PAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {69 5a 4e 31 30 42 65 61 74 44 65 74 65 63 74 43 31 45 50 33 50 43 4d } //1 iZN10BeatDetectC1EP3PCM
		$a_01_1 = {69 5f 47 4c 45 57 5f 41 4d 44 5f 73 68 61 64 65 72 5f 73 74 65 6e 63 69 6c 5f 65 78 70 6f 72 74 } //1 i_GLEW_AMD_shader_stencil_export
		$a_01_2 = {69 5f 47 4c 45 57 5f 41 52 42 5f 73 68 61 64 6f 77 5f 61 6d 62 69 65 6e 74 } //1 i_GLEW_ARB_shadow_ambient
		$a_01_3 = {69 5f 57 47 4c 45 57 5f 45 58 54 5f 63 72 65 61 74 65 5f 63 6f 6e 74 65 78 74 5f 65 73 32 5f 70 72 6f 66 69 6c 65 } //1 i_WGLEW_EXT_create_context_es2_profile
		$a_01_4 = {69 5f 67 6c 65 77 44 65 6c 65 74 65 46 72 61 67 6d 65 6e 74 53 68 61 64 65 72 41 54 49 } //1 i_glewDeleteFragmentShaderATI
		$a_01_5 = {69 5f 67 6c 65 77 44 65 6c 65 74 65 50 72 6f 67 72 61 6d 50 69 70 65 6c 69 6e 65 73 } //1 i_glewDeleteProgramPipelines
		$a_01_6 = {69 5f 67 6c 65 77 4d 75 6c 74 69 54 65 78 53 75 62 49 6d 61 67 65 33 44 45 58 54 } //1 i_glewMultiTexSubImage3DEXT
		$a_01_7 = {69 5f 67 6c 65 77 50 61 73 73 54 65 78 43 6f 6f 72 64 41 54 49 } //1 i_glewPassTexCoordATI
		$a_01_8 = {69 6c 63 5f 65 6e 74 72 79 5f 6c 69 63 65 6e 73 65 5f 5f 33 5f 30 5f 30 66 } //1 ilc_entry_license__3_0_0f
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}